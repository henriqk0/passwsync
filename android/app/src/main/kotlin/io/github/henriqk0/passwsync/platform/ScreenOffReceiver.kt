package io.github.henriqk0.passwsync.platform

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import io.github.henriqk0.passwsync.CoreExecutor
import io.github.henriqk0.passwsync.core.PasswsyncCore

/** Screen off locks every wallet and clears the clipboard (S11; FR-017, FR-022). */
class ScreenOffReceiver(
    private val core: PasswsyncCore,
    private val executor: CoreExecutor,
) : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_SCREEN_OFF) executor.run({ core.onScreenOff() })
    }

    companion object {
        /** Registered at runtime, never in the manifest; not exported. */
        fun register(context: Context, core: PasswsyncCore, executor: CoreExecutor) {
            context.registerReceiver(
                ScreenOffReceiver(core, executor),
                IntentFilter(Intent.ACTION_SCREEN_OFF),
                Context.RECEIVER_NOT_EXPORTED,
            )
        }
    }
}
