package io.github.henriqk0.passwsync.platform

import android.util.Log
import io.github.henriqk0.passwsync.core.LogSink

/** The LogSink port (S8; FR-057): closed-set lines from the core, info level only. */
class LogcatSink : LogSink {
    override fun line(text: String) {
        val line = text
        Log.i(TAG, line)
    }

    private companion object {
        const val TAG = "passwsync"
    }
}
