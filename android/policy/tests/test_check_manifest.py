"""check_manifest.py: one negative test per manifest (M1-M13), resource XML (X1-X7) and Gradle
(G1-G7) rule, each a single violation applied to the good fixture, plus the positive case."""

import unittest

from support import PolicyCase, mutate

MAN = "app/src/main/AndroidManifest.xml"
RES = "app/src/main/res"
LAYOUT = f"{RES}/layout/screen_unlock.xml"
DXR = f"{RES}/xml/data_extraction_rules.xml"
NSC = f"{RES}/xml/network_security_config.xml"
STRINGS = f"{RES}/values/strings.xml"
THEMES = f"{RES}/values/themes.xml"
APP = "app/build.gradle.kts"
SETTINGS = "settings.gradle.kts"
TOML = "gradle/libs.versions.toml"
PRO = "app/proguard-rules.pro"

APP_OPEN = '<application\n        android:name=".PasswsyncApp"'
BEFORE_APP_END = "    </application>"
SERVICE = """        <service
            android:name=".platform.CoreJobService"
            android:exported="false"
            android:permission="android.permission.BIND_JOB_SERVICE" />"""
PERM = '    <uses-permission android:name="android.permission.INTERNET" />'
MAIN_FILTER_END = "            </intent-filter>"


def repl(path, find, replace):
    return ("replace", path, find, replace)


def add(path, content):
    return ("add", path, content)


def delete(path):
    return ("delete", path)


def before_app_end(xml):
    return repl(MAN, BEFORE_APP_END, xml + "\n" + BEFORE_APP_END)


def app_attr(attr):
    return repl(MAN, APP_OPEN, APP_OPEN + "\n        " + attr)


def perm(name):
    return repl(MAN, PERM, PERM + f'\n    <uses-permission android:name="{name}" />')


DENY = ["CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
        "NEARBY_WIFI_DEVICES", "READ_CONTACTS", "GET_ACCOUNTS", "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "MANAGE_EXTERNAL_STORAGE",
        "POST_NOTIFICATIONS", "RECEIVE_BOOT_COMPLETED", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
        "SCHEDULE_EXACT_ALARM", "USE_EXACT_ALARM", "FOREGROUND_SERVICE",
        "FOREGROUND_SERVICE_DATA_SYNC", "WAKE_LOCK", "SYSTEM_ALERT_WINDOW", "QUERY_ALL_PACKAGES",
        "READ_LOGS"]
DOMAINS = ["root", "file", "database", "sharedpref", "external", "device_root", "device_file",
           "device_database", "device_sharedpref"]

CASES = {
    # --- manifest ---
    "M1_allow_backup": ("M1", repl(MAN, 'android:allowBackup="false"', 'android:allowBackup="true"')),
    "M1_fragile_data": ("M1", repl(MAN, 'android:hasFragileUserData="false"', 'android:hasFragileUserData="true"')),
    "M1_full_backup_content": ("M1", repl(MAN, 'android:fullBackupContent="false"', 'android:fullBackupContent="@xml/backup"')),
    "M1_backup_agent": ("M1", app_attr('android:backupAgent=".Agent"')),
    "M1_allow_backup_missing": ("M1", repl(MAN, 'android:allowBackup="false"', "")),
    "M2_other_rules": ("M2", repl(MAN, '"@xml/data_extraction_rules"', '"@xml/other_rules"')),
    "M2_rules_file_missing": ("M2", delete(DXR)),
    "M3_cleartext": ("M3", repl(MAN, 'android:usesCleartextTraffic="false"', 'android:usesCleartextTraffic="true"')),
    "M3_no_nsc": ("M3", repl(MAN, 'android:networkSecurityConfig="@xml/network_security_config"', "")),
    "M4_extra_permission": ("M4", perm("android.permission.VIBRATE")),
    "M4_missing_permission": ("M4", repl(MAN, PERM, "")),
    "M4_sdk23_permission": ("M4", repl(MAN, PERM, PERM + '\n    <uses-permission-sdk-23 android:name="android.permission.INTERNET" />')),
    "M4_declared_permission": ("M4", repl(MAN, PERM, PERM + '\n    <permission android:name="io.github.x.P" />')),
    "M4_max_sdk": ("M4", repl(MAN, 'android:name="android.permission.INTERNET" />', 'android:name="android.permission.INTERNET" android:maxSdkVersion="34" />')),
    "M5_ad_id": ("M5", perm("com.google.android.gms.permission.AD_ID")),
    "M6_second_exported_activity": ("M6", before_app_end('        <activity android:name=".Other" android:exported="true" />')),
    "M6_second_intent_filter": ("M6", repl(MAN, MAIN_FILTER_END, MAIN_FILTER_END + '\n            <intent-filter><action android:name="android.intent.action.SEND" /></intent-filter>')),
    "M6_extra_action": ("M6", repl(MAN, '<action android:name="android.intent.action.MAIN" />', '<action android:name="android.intent.action.MAIN" />\n                <action android:name="android.intent.action.VIEW" />')),
    "M6_data_in_filter": ("M6", repl(MAN, '<category android:name="android.intent.category.LAUNCHER" />', '<category android:name="android.intent.category.LAUNCHER" />\n                <data android:scheme="passwsync" />')),
    "M6_task_affinity": ("M6", repl(MAN, 'android:taskAffinity=""', 'android:taskAffinity="io.x"')),
    "M6_reparenting": ("M6", repl(MAN, 'android:allowTaskReparenting="false"', 'android:allowTaskReparenting="true"')),
    "M6_wrong_activity": ("M6", repl(MAN, 'android:name=".MainActivity"', 'android:name=".OtherActivity"')),
    "M7_implicit_export": ("M7", before_app_end('        <activity android:name=".Other" />')),
    "M7_exported_service": ("M7", repl(MAN, SERVICE, SERVICE.replace('android:exported="false"', 'android:exported="true"'))),
    "M8_provider": ("M8", before_app_end('        <provider android:name=".P" android:authorities="io.x" android:exported="false" />')),
    "M8_receiver": ("M8", before_app_end('        <receiver android:name=".R" android:exported="false" />')),
    "M8_alias": ("M8", before_app_end('        <activity-alias android:name=".A" android:targetActivity=".MainActivity" android:exported="false" />')),
    "M8_queries": ("M8", repl(MAN, PERM, PERM + '\n    <queries><package android:name="com.x" /></queries>')),
    "M8_shared_user": ("M8", repl(MAN, '<manifest xmlns:android="http://schemas.android.com/apk/res/android"', '<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:sharedUserId="io.x"')),
    "M9_second_service": ("M9", before_app_end('        <service android:name=".platform.Other" android:exported="false" android:permission="android.permission.BIND_JOB_SERVICE" />')),
    "M9_no_job_permission": ("M9", repl(MAN, '            android:permission="android.permission.BIND_JOB_SERVICE" />', "            />")),
    "M9_foreground_type": ("M9", repl(MAN, 'android:name=".platform.CoreJobService"', 'android:name=".platform.CoreJobService"\n            android:foregroundServiceType="dataSync"')),
    "M9_wrong_service": ("M9", repl(MAN, 'android:name=".platform.CoreJobService"', 'android:name=".platform.SyncService"')),
    "M10_process": ("M10", repl(MAN, 'android:name=".platform.CoreJobService"', 'android:name=".platform.CoreJobService"\n            android:process=":remote"')),
    "M11_debuggable": ("M11", app_attr('android:debuggable="false"')),
    "M11_test_only": ("M11", app_attr('android:testOnly="true"')),
    "M12_gms_meta": ("M12", before_app_end('        <meta-data android:name="com.google.android.gms.version" android:value="1" />')),
    "M12_firebase_meta": ("M12", before_app_end('        <meta-data android:name="firebase_analytics_collection_enabled" android:value="false" />')),
    "M12_uses_library": ("M12", before_app_end('        <uses-library android:name="org.apache.http.legacy" android:required="false" />')),
    "M13_uses_sdk": ("M13", repl(MAN, PERM, PERM + '\n    <uses-sdk android:minSdkVersion="33" />')),
    # --- resource XML ---
    "X1_malformed_layout": ("X1", repl(LAYOUT, "</LinearLayout>", "")),
    "X1_doctype": ("X1", repl(STRINGS, '<?xml version="1.0" encoding="utf-8"?>', '<?xml version="1.0" encoding="utf-8"?>\n<!DOCTYPE resources [<!ENTITY x "y">]>')),
    "X1_malformed_manifest": ("X1", repl(MAN, "</manifest>", "")),
    "X2_include": ("X2", repl(DXR, "<cloud-backup>", '<cloud-backup>\n        <include domain="file" path="wallets" />')),
    "X2_encryption_flag": ("X2", repl(DXR, "<cloud-backup>", '<cloud-backup disableIfNoEncryptionCapabilities="false">')),
    "X2_no_device_transfer": ("X2", ("regex", DXR, r"(?s)\s*<device-transfer>.*</device-transfer>", "")),
    "X3_user_certs": ("X3", repl(NSC, '<certificates src="system" />', '<certificates src="system" />\n            <certificates src="user" />')),
    "X3_domain_config": ("X3", repl(NSC, "</network-security-config>", '    <domain-config><domain>x.org</domain></domain-config>\n</network-security-config>')),
    "X3_debug_overrides": ("X3", repl(NSC, "</network-security-config>", "    <debug-overrides />\n</network-security-config>")),
    "X3_cleartext": ("X3", repl(NSC, 'cleartextTrafficPermitted="false"', 'cleartextTrafficPermitted="true"')),
    "X3_override_pins": ("X3", repl(NSC, '<certificates src="system" />', '<certificates src="system" overridePins="true" />')),
    "X3_pin_set": ("X3", repl(NSC, "</base-config>", "    <pin-set />\n    </base-config>")),
    "X4_no_text_password": ("X4", repl(LAYOUT, 'android:inputType="textPassword|textNoSuggestions"', 'android:inputType="textNoSuggestions"')),
    "X4_no_suggestions_missing": ("X4", repl(LAYOUT, 'android:inputType="textPassword|textNoSuggestions"', 'android:inputType="textPassword"')),
    "X4_no_personalized_learning": ("X4", repl(LAYOUT, 'android:imeOptions="actionDone|flagNoPersonalizedLearning"', 'android:imeOptions="actionDone"')),
    "X4_autofill_missing": ("X4", repl(LAYOUT, 'android:importantForAutofill="noExcludeDescendants" />', "/>")),
    "X4_autofill_yes": ("X4", repl(LAYOUT, 'android:importantForAutofill="noExcludeDescendants"', 'android:importantForAutofill="yes"')),
    "X4_autofill_hints": ("X4", repl(LAYOUT, 'android:importantForAutofill="noExcludeDescendants"', 'android:importantForAutofill="noExcludeDescendants"\n        android:autofillHints="password"')),
    "X4_password_by_input_type": ("X4", repl(LAYOUT, 'android:inputType="text" />', 'android:inputType="textVisiblePassword" />')),
    "X5_webview": ("X5", repl(LAYOUT, "</LinearLayout>", '    <WebView android:layout_width="1dp" android:layout_height="1dp" />\n</LinearLayout>')),
    "X5_autolink": ("X5", repl(LAYOUT, 'android:text="@string/unlock_title" />', 'android:text="@string/unlock_title"\n        android:autoLink="web" />')),
    "X5_video": ("X5", repl(LAYOUT, "</LinearLayout>", '    <VideoView android:layout_width="1dp" android:layout_height="1dp" />\n</LinearLayout>')),
    "X6_button_without_label": ("X6", repl(LAYOUT, 'android:text="@string/unlock" />', "/>")),
    "X6_edit_text_without_hint": ("X6", repl(LAYOUT, 'android:hint="@string/search"\n', "")),
    "X6_hard_coded_text": ("X6", repl(LAYOUT, 'android:text="@string/unlock"', 'android:text="Unlock"')),
    "X6_image_button_without_label": ("X6", repl(LAYOUT, 'android:contentDescription="@string/lock_all" />', "/>")),
    "X6_second_locale": ("X6", add(f"{RES}/values-de/strings.xml", '<?xml version="1.0" encoding="utf-8"?>\n<resources><string name="unlock">Entsperren</string></resources>\n')),
    "X7_material_theme": ("X7", repl(THEMES, 'parent="android:Theme.DeviceDefault.DayNight"', 'parent="android:Theme.Material"')),
    "X7_disable_preview": ("X7", repl(THEMES, "</style>", '    <item name="android:windowDisablePreview">true</item>\n    </style>')),
    "X7_no_app_theme": ("X7", repl(MAN, 'android:theme="@style/Theme.Passwsync"', 'android:theme="@style/Theme.Missing"')),
    # --- Gradle ---
    "G1_min_sdk": ("G1", repl(APP, "minSdk = 33", "minSdk = 32")),
    "G1_target_sdk": ("G1", repl(APP, "targetSdk = 37", "targetSdk = 36")),
    "G1_compile_sdk": ("G1", repl(APP, "compileSdk = 37", "compileSdk = 36")),
    "G1_application_id": ("G1", repl(APP, 'applicationId = "io.github.henriqk0.passwsync"', 'applicationId = "io.github.other"')),
    "G2_debuggable": ("G2", repl(APP, "isDebuggable = false", "isDebuggable = true")),
    "G2_not_minified": ("G2", repl(APP, "isMinifyEnabled = true", "isMinifyEnabled = false")),
    "G2_jni_debuggable": ("G2", repl(APP, "isJniDebuggable = false", "isJniDebuggable = true")),
    "G2_coverage": ("G2", repl(APP, "isMinifyEnabled = true", "isMinifyEnabled = true\n            enableUnitTestCoverage = true")),
    "G3_kotlin_plugin": ("G3", repl(APP, "alias(libs.plugins.android.application)", 'alias(libs.plugins.android.application)\n    id("org.jetbrains.kotlin.android")')),
    "G3_catalog_plugin": ("G3", repl(TOML, "[plugins]", '[plugins]\nkotlin-android = { id = "org.jetbrains.kotlin.android", version = "2.3.0" }')),
    "G3_kotlin_shorthand": ("G3", repl(APP, "alias(libs.plugins.android.application)", 'alias(libs.plugins.android.application)\n    kotlin("android")')),
    "G4_extra_dependency": ("G4", repl(APP, 'implementation(variantOf(libs.jna) { artifactType("aar") })', 'implementation(variantOf(libs.jna) { artifactType("aar") })\n    implementation(libs.okhttp)')),
    "G4_catalog_library": ("G4", repl(TOML, "[plugins]", 'okhttp = { module = "com.squareup.okhttp3:okhttp", version = "5.0.0" }\n\n[plugins]')),
    "G4_dynamic_version": ("G4", repl(TOML, 'jna = "5.19.1"', 'jna = "5.+"')),
    "G4_snapshot": ("G4", repl(TOML, 'jna = "5.19.1"', 'jna = "5.19.1-SNAPSHOT"')),
    "G4_wrong_version": ("G4", repl(TOML, 'jna = "5.19.1"', 'jna = "5.18.0"')),
    "G4_literal_coordinate": ("G4", repl(APP, 'implementation(variantOf(libs.jna) { artifactType("aar") })', 'implementation("net.java.dev.jna:jna:5.19.1@aar")')),
    "G4_test_dependency": ("G4", repl(APP, 'implementation(variantOf(libs.jna) { artifactType("aar") })', 'implementation(variantOf(libs.jna) { artifactType("aar") })\n    testImplementation(libs.jna)')),
    "G5_jcenter": ("G5", repl(SETTINGS, "        mavenCentral()\n    }\n}\n\ndependencyResolutionManagement", "        mavenCentral()\n        jcenter()\n    }\n}\n\ndependencyResolutionManagement")),
    "G5_maven_local": ("G5", repl(SETTINGS, "        google()\n        mavenCentral()\n    }\n}\n\nrootProject", "        google()\n        mavenCentral()\n        mavenLocal()\n    }\n}\n\nrootProject")),
    "G5_maven_url": ("G5", repl(SETTINGS, "        google()\n        mavenCentral()\n    }\n}\n\nrootProject", '        google()\n        mavenCentral()\n        maven(url = "https://repo.example.org")\n    }\n}\n\nrootProject')),
    "G5_project_repos": ("G5", repl(SETTINGS, "repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)", "")),
    "G6_dependencies_info": ("G6", repl(APP, "includeInApk = false", "includeInApk = true")),
    "G6_dependencies_info_missing": ("G6", repl(APP, "includeInBundle = false", "")),
    "G6_build_config": ("G6", repl(APP, "buildConfig = false", "buildConfig = true")),
    "G6_exec": ("G6", repl(APP, "dependencies {", 'tasks.register<Exec>("x") { commandLine("true") }\n\ndependencies {')),
    "G6_process_builder": ("G6", repl(APP, "dependencies {", 'val p = ProcessBuilder("true")\n\ndependencies {')),
    "G7_no_jna_keep": ("G7", repl(PRO, "-keep class com.sun.jna.** { *; }\n", "")),
    "G7_no_core_keep": ("G7", repl(PRO, "-keep class io.github.henriqk0.passwsync.core.** { *; }\n", "")),
    "G7_keep_source_file": ("G7", repl(PRO, "-keep class com.sun.jna.**", "-keepattributes SourceFile,LineNumberTable\n-keep class com.sun.jna.**")),
    "G7_print_mapping": ("G7", repl(PRO, "-keep class com.sun.jna.**", "-printmapping /tmp/mapping.txt\n-keep class com.sun.jna.**")),
}

for name in DENY:
    CASES[f"M5_{name.lower()}"] = ("M5", perm(f"android.permission.{name}"))
for section in ("cloud-backup", "device-transfer"):
    for domain in DOMAINS:
        CASES[f"X2_{section.replace('-', '_')}_{domain}"] = ("X2", ("drop", section, domain))


def apply(root, change):
    kind = change[0]
    if kind == "replace":
        mutate(root / change[1], change[2], change[3])
    elif kind == "add":
        path = root / change[1]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(change[2], encoding="utf-8")
    elif kind == "delete":
        (root / change[1]).unlink()
    elif kind == "regex":
        import re
        path = root / change[1]
        text, count = re.subn(change[2], change[3], path.read_text(encoding="utf-8"))
        assert count, change
        path.write_text(text, encoding="utf-8")
    elif kind == "drop":
        _, section, domain = change
        path = root / DXR
        text = path.read_text(encoding="utf-8")
        start = text.index(f"<{section}>")
        line = f'        <exclude domain="{domain}" path="." />\n'
        at = text.index(line, start)
        path.write_text(text[:at] + text[at + len(line):], encoding="utf-8")
    else:
        raise AssertionError(kind)


class CheckManifest(PolicyCase):
    checker = "check_manifest"

    def test_good_fixture_passes(self):
        self.assertPasses(self.tree())

    def test_usage_error(self):
        from support import run_checker
        self.assertEqual(run_checker(self.checker, "/nonexistent")[0], 64)


def make(rule, change):
    def test(self):
        root = self.tree()
        apply(root, change)
        self.assertFails(root, rule)
    return test


for case, (rule, change) in CASES.items():
    setattr(CheckManifest, f"test_{case}", make(rule, change))


if __name__ == "__main__":
    unittest.main()
