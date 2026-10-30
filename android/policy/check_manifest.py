"""Manifest (M1-M13), resource XML (X1-X7) and Gradle (G1-G7) rules of
contracts/android-policy.md sections 1-3.

usage: python3 -I check_manifest.py <android-dir>
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import Finding, XmlError, android, parse_xml, rel, run_main  # noqa: E402

RULES = [f"M{i}" for i in range(1, 14)] + [f"X{i}" for i in range(1, 8)] + [f"G{i}" for i in range(1, 8)]

MANIFEST = "app/src/main/AndroidManifest.xml"
RES = "app/src/main/res"

ALLOWED_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE",
    "android.permission.ACCESS_LOCAL_NETWORK",
}
DENIED = re.compile(
    r"^(android\.permission\.(CAMERA|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|"
    r"ACCESS_BACKGROUND_LOCATION|NEARBY_WIFI_DEVICES|READ_CONTACTS|GET_ACCOUNTS|"
    r"READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|READ_MEDIA_\w*|MANAGE_EXTERNAL_STORAGE|"
    r"POST_NOTIFICATIONS|RECEIVE_BOOT_COMPLETED|REQUEST_IGNORE_BATTERY_OPTIMIZATIONS|"
    r"SCHEDULE_EXACT_ALARM|USE_EXACT_ALARM|FOREGROUND_SERVICE\w*|WAKE_LOCK|SYSTEM_ALERT_WINDOW|"
    r"QUERY_ALL_PACKAGES|READ_LOGS)|com\.google\.android\.gms\.permission\.AD_ID)$"
)
COMPONENTS = ("activity", "service", "receiver", "provider", "activity-alias")
MAIN_ACTIVITY = {".MainActivity", "io.github.henriqk0.passwsync.MainActivity"}
JOB_SERVICE = {".platform.CoreJobService", "io.github.henriqk0.passwsync.platform.CoreJobService"}
PROPRIETARY_META = re.compile(r"com\.google\.|firebase|gms|(^|[._:-])ads([._:-]|$)|analytics|crashlytics", re.I)
DOMAINS = ["root", "file", "database", "sharedpref", "external", "device_root", "device_file",
           "device_database", "device_sharedpref"]
LABELLED = {"Button", "ImageButton", "EditText", "Switch", "CheckBox", "RadioButton", "Spinner"}
TEXT_ATTRS = ("text", "hint", "contentDescription", "title", "tooltipText")


def local(tag: str) -> str:
    return tag.rsplit(".", 1)[-1]


def a(element, attr):
    return element.get(android(attr))


class Tree:
    """Parsed XML files of the tree; X1 findings for the unparseable ones."""

    def __init__(self, root: Path, findings):
        self.root = root
        self.findings = findings
        self.parsed = {}
        files = [root / MANIFEST] + sorted((root / RES).rglob("*.xml"))
        for path in files:
            if not path.is_file():
                continue
            try:
                self.parsed[path] = parse_xml(path)
            except XmlError as error:
                findings.append(Finding("X1", f"{rel(path, root)}: {error}"))

    def get(self, relpath):
        return self.parsed.get(self.root / relpath)


# --- manifest -----------------------------------------------------------------------------


def check_manifest(tree: Tree, out):
    m = tree.get(MANIFEST)
    if m is None:
        if not (tree.root / MANIFEST).is_file():
            out.append(Finding("M1", f"{MANIFEST} is missing"))
        return
    app = m.find("application")
    if app is None:
        out.append(Finding("M1", "no <application> element"))
        return

    # M1
    if a(app, "allowBackup") != "false":
        out.append(Finding("M1", 'application must set android:allowBackup="false"'))
    if a(app, "hasFragileUserData") != "false":
        out.append(Finding("M1", 'application must set android:hasFragileUserData="false"'))
    if a(app, "fullBackupContent") not in (None, "false"):
        out.append(Finding("M1", 'android:fullBackupContent other than "false"'))
    if a(app, "backupAgent") is not None:
        out.append(Finding("M1", "android:backupAgent is not allowed"))
    # M2
    if a(app, "dataExtractionRules") != "@xml/data_extraction_rules":
        out.append(Finding("M2", 'android:dataExtractionRules must be "@xml/data_extraction_rules"'))
    if not (tree.root / RES / "xml/data_extraction_rules.xml").is_file():
        out.append(Finding("M2", "res/xml/data_extraction_rules.xml is missing"))
    # M3
    if a(app, "networkSecurityConfig") != "@xml/network_security_config":
        out.append(Finding("M3", 'android:networkSecurityConfig must be "@xml/network_security_config"'))
    if a(app, "usesCleartextTraffic") != "false":
        out.append(Finding("M3", 'android:usesCleartextTraffic must be "false"'))

    # M5 before M4 so a denied name is reported by name first.
    names = []
    for tag in ("uses-permission", "uses-permission-sdk-23"):
        for perm in m.iter(tag):
            name = a(perm, "name") or ""
            names.append(name)
            if DENIED.match(name):
                out.append(Finding("M5", f"denied permission {name}"))
            if tag != "uses-permission":
                out.append(Finding("M4", f"<{tag}> is not allowed ({name})"))
            if a(perm, "maxSdkVersion") is not None:
                out.append(Finding("M4", f"maxSdkVersion on {name}"))
    plain = [a(p, "name") for p in m.iter("uses-permission")]
    if set(plain) != ALLOWED_PERMISSIONS or len(plain) != len(set(plain)):
        extra = sorted(set(plain) - ALLOWED_PERMISSIONS)
        missing = sorted(ALLOWED_PERMISSIONS - set(plain))
        out.append(Finding("M4", f"permission set differs from the allow-list (extra {extra}, missing {missing})"))
    for tag in ("permission", "permission-tree", "permission-group"):
        if m.find(f".//{tag}") is not None:
            out.append(Finding("M4", f"<{tag}> is not allowed"))

    # M6
    activities = list(app.iter("activity"))
    exported = [act for act in activities if a(act, "exported") == "true"]
    main = exported[0] if len(exported) == 1 else None
    if len(exported) != 1:
        out.append(Finding("M6", f"exactly one exported activity expected, found {len(exported)}"))
    if main is not None:
        if a(main, "name") not in MAIN_ACTIVITY:
            out.append(Finding("M6", "the exported activity must be .MainActivity"))
        filters = main.findall("intent-filter")
        if len(filters) != 1:
            out.append(Finding("M6", f"MainActivity must have exactly one intent-filter, found {len(filters)}"))
        else:
            f = filters[0]
            actions = [a(x, "name") for x in f.findall("action")]
            categories = [a(x, "name") for x in f.findall("category")]
            others = [c.tag for c in f if c.tag not in ("action", "category")]
            if actions != ["android.intent.action.MAIN"] or categories != ["android.intent.category.LAUNCHER"] or others:
                out.append(Finding("M6", "the intent-filter must be exactly MAIN + LAUNCHER without <data>"))
        if a(main, "taskAffinity") != "":
            out.append(Finding("M6", 'MainActivity must set android:taskAffinity=""'))
        if a(main, "allowTaskReparenting") != "false":
            out.append(Finding("M6", 'MainActivity must set android:allowTaskReparenting="false"'))

    # M7
    for tag in COMPONENTS:
        for comp in app.iter(tag):
            value = a(comp, "exported")
            if value is None:
                out.append(Finding("M7", f"<{tag} {a(comp, 'name')}> must declare android:exported"))
            elif comp is not main and value != "false":
                out.append(Finding("M7", f'<{tag} {a(comp, "name")}> must be android:exported="false"'))

    # M8
    for tag in ("provider", "receiver", "activity-alias", "queries", "data"):
        if m.find(f".//{tag}") is not None:
            out.append(Finding("M8", f"<{tag}> is not allowed"))
    all_filters = list(m.iter("intent-filter"))
    main_filters = main.findall("intent-filter") if main is not None else []
    if len(all_filters) != len(main_filters) or len(main_filters) > 1:
        out.append(Finding("M8", "no intent-filter other than MainActivity's launcher filter"))
    if a(m, "sharedUserId") is not None:
        out.append(Finding("M8", "android:sharedUserId is not allowed"))

    # M9
    services = list(app.iter("service"))
    if len(services) != 1:
        out.append(Finding("M9", f"exactly one <service> expected, found {len(services)}"))
    for svc in services:
        if a(svc, "name") not in JOB_SERVICE:
            out.append(Finding("M9", f"unexpected service {a(svc, 'name')}"))
        if a(svc, "exported") != "false":
            out.append(Finding("M9", "CoreJobService must not be exported"))
        if a(svc, "permission") != "android.permission.BIND_JOB_SERVICE":
            out.append(Finding("M9", "CoreJobService must require BIND_JOB_SERVICE"))
        if a(svc, "foregroundServiceType") is not None:
            out.append(Finding("M9", "no foregroundServiceType"))
        if svc.find("intent-filter") is not None:
            out.append(Finding("M9", "CoreJobService must have no intent-filter"))

    for element in m.iter():
        # M10, M11
        if a(element, "process") is not None:
            out.append(Finding("M10", f"android:process on <{element.tag}>"))
        if a(element, "debuggable") is not None:
            out.append(Finding("M11", f"android:debuggable on <{element.tag}>"))
        if a(element, "testOnly") is not None:
            out.append(Finding("M11", f"android:testOnly on <{element.tag}>"))
    # M12
    if m.find(".//uses-library") is not None:
        out.append(Finding("M12", "<uses-library> is not allowed"))
    for meta in m.iter("meta-data"):
        for value in (a(meta, "name") or "", a(meta, "value") or ""):
            if PROPRIETARY_META.search(value):
                out.append(Finding("M12", f"<meta-data> naming {value}"))
    # M13
    if m.find(".//uses-sdk") is not None:
        out.append(Finding("M13", "<uses-sdk> must not be in the manifest (SDK levels live in Gradle)"))


# --- resource XML ---------------------------------------------------------------------------


def check_resources(tree: Tree, out):
    res = tree.root / RES
    # X2
    dxr = tree.get(f"{RES}/xml/data_extraction_rules.xml")
    if dxr is not None:
        if dxr.tag != "data-extraction-rules":
            out.append(Finding("X2", "root must be <data-extraction-rules>"))
        for section in ("cloud-backup", "device-transfer"):
            node = dxr.find(section)
            if node is None:
                out.append(Finding("X2", f"<{section}> is missing"))
                continue
            excluded = {x.get("domain") for x in node.findall("exclude") if x.get("path") == "."}
            for domain in DOMAINS:
                if domain not in excluded:
                    out.append(Finding("X2", f'<{section}> must exclude domain="{domain}" path="."'))
            if node.find(".//include") is not None:
                out.append(Finding("X2", f"<{section}> must not contain <include>"))
        cloud = dxr.find("cloud-backup")
        if cloud is not None and cloud.get("disableIfNoEncryptionCapabilities") == "false":
            out.append(Finding("X2", 'disableIfNoEncryptionCapabilities="false" is not allowed'))
        if any(x is not None for x in dxr.iterfind("include")):
            out.append(Finding("X2", "<include> is not allowed"))
    elif not (res / "xml/data_extraction_rules.xml").is_file():
        out.append(Finding("X2", "res/xml/data_extraction_rules.xml is missing"))

    # X3
    nsc = tree.get(f"{RES}/xml/network_security_config.xml")
    if nsc is None:
        if not (res / "xml/network_security_config.xml").is_file():
            out.append(Finding("X3", "res/xml/network_security_config.xml is missing"))
    else:
        bases = nsc.findall("base-config")
        if len(bases) != 1 or bases[0].get("cleartextTrafficPermitted") != "false":
            out.append(Finding("X3", 'exactly one <base-config cleartextTrafficPermitted="false">'))
        for base in bases:
            anchors = base.findall("trust-anchors")
            certs = [c for t in anchors for c in t]
            if len(anchors) != 1 or [(c.tag, c.get("src")) for c in certs] != [("certificates", "system")]:
                out.append(Finding("X3", 'trust-anchors must contain only <certificates src="system"/>'))
        for tag in ("domain-config", "debug-overrides", "pin-set"):
            if nsc.find(f".//{tag}") is not None:
                out.append(Finding("X3", f"<{tag}> is not allowed"))
        for element in nsc.iter():
            if element.get("src") == "user":
                out.append(Finding("X3", 'src="user" is not allowed'))
            if element.get("overridePins") is not None:
                out.append(Finding("X3", "overridePins is not allowed"))

    # X4, X5, X6 over every layout
    for path, root in tree.parsed.items():
        if path.parent.parent != res or not path.parent.name.startswith("layout"):
            continue
        name = rel(path, tree.root)
        labels_for = {a(e, "labelFor") for e in root.iter() if a(e, "labelFor")}
        for e in root.iter():
            tag = local(e.tag)
            ident = (a(e, "id") or "").split("/")[-1]
            input_type = a(e, "inputType") or ""
            if tag.endswith("EditText") and ("password" in ident.lower() or "Password" in input_type):
                ime = a(e, "imeOptions") or ""
                if "textPassword" not in input_type.split("|") or "textNoSuggestions" not in input_type.split("|"):
                    out.append(Finding("X4", f"{name}: {ident} needs inputType textPassword|textNoSuggestions"))
                if "flagNoPersonalizedLearning" not in ime:
                    out.append(Finding("X4", f"{name}: {ident} needs imeOptions flagNoPersonalizedLearning"))
                if a(e, "importantForAutofill") not in ("noExcludeDescendants", "no"):
                    out.append(Finding("X4", f'{name}: {ident} needs importantForAutofill="noExcludeDescendants"'))
                if a(e, "autofillHints") is not None:
                    out.append(Finding("X4", f"{name}: {ident} must not have autofillHints"))
            if tag in ("WebView", "VideoView", "SurfaceView") or e.tag.startswith("android.webkit."):
                out.append(Finding("X5", f"{name}: <{e.tag}> is not allowed"))
            if a(e, "autoLink") is not None:
                out.append(Finding("X5", f"{name}: android:autoLink is not allowed"))
            clickable_image = tag == "ImageView" and (a(e, "clickable") == "true" or a(e, "onClick"))
            if tag in LABELLED or tag.endswith("EditText") or clickable_image:
                if tag.endswith("EditText"):
                    labelled = a(e, "hint") or f"@id/{ident}" in labels_for or f"@+id/{ident}" in labels_for
                else:
                    labelled = a(e, "contentDescription") or a(e, "text") or a(e, "hint")
                if not labelled:
                    out.append(Finding("X6", f"{name}: <{tag} {ident}> has no accessibility label"))
            for attr in TEXT_ATTRS:
                value = a(e, attr)
                if value is not None and not value.startswith("@string/"):
                    out.append(Finding("X6", f"{name}: android:{attr} must be a @string/ reference"))
    if not (res / "values/strings.xml").is_file():
        out.append(Finding("X6", "res/values/strings.xml is missing"))
    if res.is_dir():
        for folder in sorted(res.iterdir()):
            if folder.is_dir() and folder.name.startswith("values-") and (folder / "strings.xml").exists():
                out.append(Finding("X6", f"locale folder {folder.name} is not allowed (English only)"))

    # X7
    m = tree.get(MANIFEST)
    app = m.find("application") if m is not None else None
    theme_ref = a(app, "theme") if app is not None else None
    themes = tree.get(f"{RES}/values/themes.xml")
    if themes is None:
        out.append(Finding("X7", "res/values/themes.xml is missing or unreadable"))
        return
    styles = {s.get("name"): s for s in themes.iter("style")}
    theme = styles.get((theme_ref or "").removeprefix("@style/"))
    if theme is None:
        out.append(Finding("X7", f"application theme {theme_ref} is not defined in values/themes.xml"))
    elif not (theme.get("parent") or "").startswith("android:Theme.DeviceDefault"):
        out.append(Finding("X7", "the app theme parent must be android:Theme.DeviceDefault*"))
    for item in themes.iter("item"):
        if item.get("name") in ("android:windowDisablePreview", "android:windowShowWallpaper"):
            out.append(Finding("X7", f"{item.get('name')} is not allowed"))


# --- Gradle ---------------------------------------------------------------------------------


def kts(text: str) -> str:
    """Drops `//` and `/* */` comments of a Gradle Kotlin script (strings are kept: the
    rules name literals)."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return "\n".join(re.sub(r"(^|\s)//.*$", "", line) for line in text.splitlines())


def block(text: str, name: str):
    """Bodies of every `name {` block (tolerant brace matching)."""
    bodies = []
    for match in re.finditer(rf"(?<![\w.]){re.escape(name)}\s*\{{", text):
        depth, start = 1, match.end()
        i = start
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        bodies.append(text[start:i - 1])
    return bodies


def read(root: Path, relpath: str, out, rule: str):
    path = root / relpath
    if not path.is_file():
        out.append(Finding(rule, f"{relpath} is missing"))
        return ""
    return path.read_text(encoding="utf-8")


def toml_sections(text: str):
    sections, current = {}, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        header = re.fullmatch(r"\[([\w.-]+)\]", line)
        if header:
            current = sections.setdefault(header.group(1), {})
        elif "=" in line and current is not None:
            key, value = line.split("=", 1)
            current[key.strip()] = value.strip()
    return sections


def check_gradle(root: Path, out):
    app = kts(read(root, "app/build.gradle.kts", out, "G1"))
    settings = kts(read(root, "settings.gradle.kts", out, "G5"))
    top = kts((root / "build.gradle.kts").read_text(encoding="utf-8")) if (root / "build.gradle.kts").is_file() else ""
    catalog_text = read(root, "gradle/libs.versions.toml", out, "G4")
    catalog = toml_sections(catalog_text)
    scripts = {"app/build.gradle.kts": app, "settings.gradle.kts": settings, "build.gradle.kts": top}

    # G1
    for key, want in (("minSdk", "33"), ("targetSdk", "37"), ("compileSdk", "37")):
        found = re.findall(rf"\b{key}\s*=\s*(\S+)", app)
        if found != [want]:
            out.append(Finding("G1", f"{key} must be {want} (found {found})"))
    if re.findall(r'\bapplicationId\s*=\s*"([^"]*)"', app) != ["io.github.henriqk0.passwsync"]:
        out.append(Finding("G1", 'applicationId must be "io.github.henriqk0.passwsync"'))

    # G2
    releases = [b for bt in block(app, "buildTypes") for b in block(bt, "release")]
    if len(releases) != 1:
        out.append(Finding("G2", "exactly one release build type expected"))
    for rel_body in releases:
        for key, want in (("isDebuggable", "false"), ("isMinifyEnabled", "true"), ("isJniDebuggable", "false")):
            if re.findall(rf"\b{key}\s*=\s*(\w+)", rel_body) != [want]:
                out.append(Finding("G2", f"release must set {key} = {want}"))
        if re.search(r"testCoverageEnabled|enableUnitTestCoverage|enableAndroidTestCoverage|\bdebuggable\b", rel_body):
            out.append(Finding("G2", "no debuggable or test coverage in release"))

    # G3
    for name, text in scripts.items():
        for body in block(text, "plugins"):
            for line in filter(None, (x.strip() for x in body.splitlines())):
                if not re.fullmatch(r"alias\(libs\.plugins\.android\.application\)(\s+apply\s+false)?", line):
                    out.append(Finding("G3", f"{name}: plugin {line!r} is not allowed"))
    plugin_ids = re.findall(r'id\s*=\s*"([^"]+)"', " ".join(catalog.get("plugins", {}).values()))
    if list(catalog.get("plugins", {})) != ["android-application"] or plugin_ids != ["com.android.application"]:
        out.append(Finding("G3", "the version catalog may declare only com.android.application"))
    if catalog.get("versions", {}).get("agp") != '"9.4.1"':
        out.append(Finding("G3", "AGP must be 9.4.1"))

    # G4
    deps = block(app, "dependencies")
    lines = [x.strip() for body in deps for x in body.splitlines() if x.strip()]
    if lines != ['implementation(variantOf(libs.jna) { artifactType("aar") })']:
        out.append(Finding("G4", f"dependencies must be exactly the JNA aar from the catalog (found {lines})"))
    libraries = catalog.get("libraries", {})
    if list(libraries) != ["jna"] or not re.fullmatch(r'\{\s*module\s*=\s*"net\.java\.dev\.jna:jna",\s*version\.ref\s*=\s*"jna"\s*\}', libraries.get("jna", "")):
        out.append(Finding("G4", "the catalog may declare only net.java.dev.jna:jna (version.ref jna)"))
    if catalog.get("versions", {}).get("jna") != '"5.19.1"':
        out.append(Finding("G4", "JNA must be 5.19.1"))
    for name, text in list(scripts.items()) + [("gradle/libs.versions.toml", catalog_text)]:
        if re.search(r'["\'][^"\']*(\+|latest\.|SNAPSHOT)[^"\']*["\']', text):
            out.append(Finding("G4", f"{name}: dynamic or SNAPSHOT version"))

    # G5
    for name, text in scripts.items():
        for body in block(text, "repositories"):
            for line in filter(None, (x.strip() for x in body.splitlines())):
                if line not in ("google()", "mavenCentral()"):
                    out.append(Finding("G5", f"{name}: repository {line!r} is not allowed"))
        if re.search(r"\bjcenter\b|\bmavenLocal\b|\bmaven\s*[({]|\bivy\s*[({]", text):
            out.append(Finding("G5", f"{name}: jcenter, mavenLocal, maven(...) and ivy are not allowed"))
    if "repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)" not in " ".join(block(settings, "dependencyResolutionManagement")):
        out.append(Finding("G5", "settings must set RepositoriesMode.FAIL_ON_PROJECT_REPOS"))

    # G6
    info = " ".join(block(app, "dependenciesInfo"))
    if not (re.search(r"\bincludeInApk\s*=\s*false\b", info) and re.search(r"\bincludeInBundle\s*=\s*false\b", info)):
        out.append(Finding("G6", "dependenciesInfo must set includeInApk = false and includeInBundle = false"))
    if re.search(r"\bincludeIn(Apk|Bundle)\s*=\s*true\b", app):
        out.append(Finding("G6", "dependency info must not be included"))
    features = " ".join(block(app, "buildFeatures"))
    if not re.search(r"\bbuildConfig\s*=\s*false\b", features) or re.search(r"\bbuildConfig\s*=\s*true\b", app):
        out.append(Finding("G6", "buildFeatures must set buildConfig = false"))
    for name, text in scripts.items():
        if re.search(r"\bExec\b|\bexec\s*[({]|ProcessBuilder|Runtime\.getRuntime|\bcommandLine\s*\(", text):
            out.append(Finding("G6", f"{name}: Exec/exec/ProcessBuilder is not allowed"))

    # G7
    pro = read(root, "app/proguard-rules.pro", out, "G7")
    rules = [x.split("#", 1)[0].strip() for x in pro.splitlines()]
    if "-keep class com.sun.jna.** { *; }" not in rules:
        out.append(Finding("G7", "proguard must keep com.sun.jna.**"))
    if "-keep class io.github.henriqk0.passwsync.core.** { *; }" not in rules:
        out.append(Finding("G7", "proguard must keep io.github.henriqk0.passwsync.core.**"))
    for line in rules:
        if line.startswith("-keepattributes") and re.search(r"SourceFile|LineNumberTable", line):
            out.append(Finding("G7", "no -keepattributes SourceFile,LineNumberTable"))
        if line.startswith("-printmapping"):
            out.append(Finding("G7", "no -printmapping"))


def check(root: Path):
    findings = []
    tree = Tree(root, findings)
    check_manifest(tree, findings)
    check_resources(tree, findings)
    check_gradle(root, findings)
    return findings


def main(argv=None):
    return run_main(sys.argv[1:] if argv is None else argv, "check_manifest.py", check)


if __name__ == "__main__":
    sys.exit(main())
