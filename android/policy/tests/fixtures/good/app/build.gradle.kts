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
}

dependencies {
    implementation(variantOf(libs.jna) { artifactType("aar") })
}
