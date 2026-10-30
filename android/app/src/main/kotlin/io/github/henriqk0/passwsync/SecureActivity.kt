package io.github.henriqk0.passwsync

import android.app.Activity
import android.os.Bundle
import android.view.WindowManager

/**
 * Base of every activity (S1; FR-026, FR-027): the window is FLAG_SECURE (no screenshot,
 * recording, casting or insecure display) and the recents thumbnail is disabled, both set
 * before the first frame and before any content view exists.
 */
abstract class SecureActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setRecentsScreenshotEnabled(false)
        super.onCreate(savedInstanceState)
    }
}
