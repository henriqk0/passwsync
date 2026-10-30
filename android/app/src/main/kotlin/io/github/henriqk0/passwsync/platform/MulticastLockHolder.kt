package io.github.henriqk0.passwsync.platform

import android.content.Context
import android.net.wifi.WifiManager
import io.github.henriqk0.passwsync.core.PasswsyncCore

/**
 * Holds the Wi-Fi multicast lock exactly while the core's node runs (S12; FR-043): the lock
 * is not reference counted, acquired when `multicastWanted()` is true and released as soon as
 * it is false. Polled after every lifecycle call and on NetworkChanged.
 */
class MulticastLockHolder(context: Context) {
    private val lock: WifiManager.MulticastLock =
        context.getSystemService(WifiManager::class.java).createMulticastLock(TAG).apply {
            setReferenceCounted(false)
        }

    /** Call on the core executor (multicastWanted is a core call). */
    fun sync(core: PasswsyncCore) {
        if (core.multicastWanted()) {
            if (!lock.isHeld) lock.acquire()
        } else if (lock.isHeld) {
            lock.release()
        }
    }

    private companion object {
        const val TAG = "passwsync"
    }
}
