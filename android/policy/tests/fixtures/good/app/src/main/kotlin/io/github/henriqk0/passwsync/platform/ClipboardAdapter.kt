package io.github.henriqk0.passwsync.platform

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import io.github.henriqk0.passwsync.Secrets
import io.github.henriqk0.passwsync.core.Clipboard

/** The Clipboard port: every clip is marked sensitive (FR-021). */
class ClipboardAdapter(context: Context) : Clipboard {
    private val manager = context.getSystemService(ClipboardManager::class.java)

    override fun setSensitive(value: ByteArray): Long {
        val clip = ClipData.newPlainText("", Secrets.platformText(value))
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
        manager.setPrimaryClip(clip)
        return manager.primaryClipDescription?.timestamp ?: 0L
    }

    override fun clearIfOurs(timestamp: Long): Boolean {
        val description = manager.primaryClipDescription ?: return run { manager.clearPrimaryClip(); true }
        if (description.timestamp != timestamp) return false
        manager.clearPrimaryClip()
        return true
    }
}
