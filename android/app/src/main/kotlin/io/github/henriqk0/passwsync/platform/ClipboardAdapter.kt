package io.github.henriqk0.passwsync.platform

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import io.github.henriqk0.passwsync.Secrets
import io.github.henriqk0.passwsync.core.Clipboard
import io.github.henriqk0.passwsync.core.PlatformException

/**
 * The Clipboard port (S3; FR-021, FR-022): the only user of the clipboard APIs. Every clip is
 * marked `EXTRA_IS_SENSITIVE`, so the system and keyboards show no preview. Clearing removes
 * the clip only when it is still ours (same timestamp) or cannot be inspected.
 */
class ClipboardAdapter(context: Context) : Clipboard {
    private val manager: ClipboardManager = context.getSystemService(ClipboardManager::class.java)

    override fun setSensitive(value: ByteArray): Long {
        try {
            val clip = ClipData.newPlainText("", Secrets.platformText(value))
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
            manager.setPrimaryClip(clip)
            return manager.primaryClipDescription?.timestamp ?: throw PlatformException.Unavailable()
        } catch (_: SecurityException) {
            throw PlatformException.Unavailable()
        } finally {
            value.fill(0)
        }
    }

    override fun clearIfOurs(timestamp: Long): Boolean {
        val description = try {
            manager.primaryClipDescription
        } catch (_: SecurityException) {
            null
        }
        if (description != null && description.timestamp != timestamp) return false
        return try {
            manager.clearPrimaryClip()
            true
        } catch (_: SecurityException) {
            false
        }
    }
}
