package io.github.henriqk0.passwsync.platform

import android.content.Context
import android.net.wifi.WifiManager
import io.github.henriqk0.passwsync.core.PasswsyncCore

/** Holds the multicast lock exactly while the core's node runs (FR-043). */
class MulticastLockHolder(context: Context) {
    private val lock = context.getSystemService(WifiManager::class.java)
        .createMulticastLock("passwsync")
        .apply { setReferenceCounted(false) }

    fun update(core: PasswsyncCore) {
        if (core.multicastWanted()) {
            if (!lock.isHeld) lock.acquire()
        } else if (lock.isHeld) {
            lock.release()
        }
    }
}
