// The passwsync Android app (007). Policy: contracts/android-policy.md G1-G7, checked by
// android/policy/check_manifest.py. The Rust library is built outside Gradle by
// android/build-rust.sh (no Exec task, research R16) into app/src/main/jniLibs.
plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "io.github.henriqk0.passwsync"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.henriqk0.passwsync"
        minSdk = 33
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isDebuggable = false
            isJniDebuggable = false
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        buildConfig = false
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    implementation(variantOf(libs.jna) { artifactType("aar") })
}
