package io.github.henriqk0.passwsync

import android.app.Activity
import android.os.Bundle
import android.view.WindowManager

/** Every screen: no screenshots, no recents thumbnail (FR-026, FR-027). */
abstract class SecureActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setRecentsScreenshotEnabled(false)
        super.onCreate(savedInstanceState)
    }
}
