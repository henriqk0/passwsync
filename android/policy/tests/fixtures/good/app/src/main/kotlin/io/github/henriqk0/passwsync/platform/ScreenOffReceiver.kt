package io.github.henriqk0.passwsync.platform

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import io.github.henriqk0.passwsync.core.PasswsyncCore

/** Screen off locks every wallet and clears the clipboard (FR-017). */
class ScreenOffReceiver(private val core: PasswsyncCore) : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_SCREEN_OFF) core.onScreenOff()
    }

    companion object {
        fun register(context: Context, core: PasswsyncCore) {
            context.registerReceiver(ScreenOffReceiver(core), IntentFilter(Intent.ACTION_SCREEN_OFF), Context.RECEIVER_NOT_EXPORTED)
        }
    }
}
